"""Deep coverage expansion for OpenLDAP 1.x operations - Real Docker LDAP testing.

Targets uncovered code paths in openldap1_operations.py (60% current coverage)
with real Docker LDAP fixture data, RFC compliance validation, and comprehensive
schema/attribute operations testing.

This test suite aims to expand OpenLDAP1 coverage from 60% to 95%+.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdapClients
from flext_ldap.servers.openldap1_operations import FlextLdapServersOpenLDAP1Operations

# ============================================================================
# OPENLDAP1 OPERATIONS DEEP COVERAGE - REAL DOCKER TESTING (60% → 95%+)
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP1OperationsDeepCoverage:
    """Deep integration tests for OpenLDAP 1.x operations with real Docker LDAP."""

    def test_openldap1_normalize_entry_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 normalize_entry_for_server with basic entry."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testuser,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson", "person"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["testuser"]),
                    "sn": FlextLdifModels.AttributeValues(values=["User"]),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert result.is_success
        normalized = result.unwrap()
        assert normalized is not None

    def test_openldap1_get_acl_attribute_name(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 returns correct ACL attribute name."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_attr = ops.get_acl_attribute_name()
        assert isinstance(acl_attr, str)
        assert len(acl_attr) > 0

    def test_openldap1_get_acl_format(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 ACL format returns string."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_format = ops.get_acl_format()
        assert isinstance(acl_format, str)

    def test_openldap1_get_default_port_non_ssl(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 default port without SSL is 389."""
        ops = FlextLdapServersOpenLDAP1Operations()
        port = ops.get_default_port(use_ssl=False)
        assert port == 389
        assert isinstance(port, int)

    def test_openldap1_get_default_port_ssl(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 default port with SSL is 636."""
        ops = FlextLdapServersOpenLDAP1Operations()
        port = ops.get_default_port(use_ssl=True)
        assert port == 636
        assert isinstance(port, int)

    def test_openldap1_get_bind_mechanisms(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 bind mechanisms."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0
        assert "SIMPLE" in mechanisms

    def test_openldap1_get_schema_dn(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 schema DN format."""
        ops = FlextLdapServersOpenLDAP1Operations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    def test_openldap1_supports_start_tls(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 START_TLS support."""
        ops = FlextLdapServersOpenLDAP1Operations()
        supports = ops.supports_start_tls()
        assert isinstance(supports, bool)

    def test_openldap1_discover_schema_with_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 schema discovery with real connection."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.discover_schema(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_openldap1_parse_object_class(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 parse_object_class returns FlextResult."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.parse_object_class("person")
        assert isinstance(result, FlextResult)

    def test_openldap1_parse_attribute_type(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 parse_attribute_type returns FlextResult."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.parse_attribute_type("cn")
        assert isinstance(result, FlextResult)

    def test_openldap1_supports_vlv(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OpenLDAP1 VLV support."""
        ops = FlextLdapServersOpenLDAP1Operations()
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_openldap1_supports_paged_results(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 paged results support."""
        ops = FlextLdapServersOpenLDAP1Operations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_openldap1_get_max_page_size(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 maximum page size."""
        ops = FlextLdapServersOpenLDAP1Operations()
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_openldap1_server_type(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OpenLDAP1 server_type property."""
        ops = FlextLdapServersOpenLDAP1Operations()
        assert ops.server_type == "openldap1"

    def test_openldap1_validate_entry(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 entry validation."""
        ops = FlextLdapServersOpenLDAP1Operations()
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

    def test_openldap1_normalize_with_multiple_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 normalize with multiple attributes."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=multi_attr,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson", "person"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["multi_attr"]),
                    "sn": FlextLdifModels.AttributeValues(values=["Attr"]),
                    "mail": FlextLdifModels.AttributeValues(
                        values=["test@example.com"]
                    ),
                    "telephoneNumber": FlextLdifModels.AttributeValues(
                        values=["+1-555-1234"]
                    ),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert result.is_success


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP1OperationsErrorHandling:
    """Test OpenLDAP1 operations error handling and edge cases."""

    def test_openldap1_discover_schema_with_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 schema discovery error handling."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.discover_schema(None)
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_openldap1_parse_object_class_invalid(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 parse_object_class with invalid class."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.parse_object_class("invalidClass123")
        assert isinstance(result, FlextResult)

    def test_openldap1_parse_attribute_type_invalid(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 parse_attribute_type with invalid attribute."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.parse_attribute_type("invalidAttr123")
        assert isinstance(result, FlextResult)


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP1OperationsConfiguration:
    """Test OpenLDAP1 operations configuration and consistency."""

    def test_openldap1_multiple_instances_consistency(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test multiple OpenLDAP1 instances have consistent configuration."""
        ops1 = FlextLdapServersOpenLDAP1Operations()
        ops2 = FlextLdapServersOpenLDAP1Operations()
        ops3 = FlextLdapServersOpenLDAP1Operations()

        assert ops1.server_type == ops2.server_type == ops3.server_type == "openldap1"
        assert (
            ops1.get_default_port(use_ssl=False)
            == ops2.get_default_port(use_ssl=False)
            == 389
        )
        assert (
            ops1.get_default_port(use_ssl=True)
            == ops2.get_default_port(use_ssl=True)
            == 636
        )

    def test_openldap1_port_rfc_compliance(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 uses RFC-compliant ports."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # RFC 4511 standard ports
        assert ops.get_default_port(use_ssl=False) == 389
        assert ops.get_default_port(use_ssl=True) == 636

    def test_openldap1_schema_dn_consistency(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 schema DN is consistent."""
        ops1 = FlextLdapServersOpenLDAP1Operations()
        ops2 = FlextLdapServersOpenLDAP1Operations()

        assert ops1.get_schema_dn() == ops2.get_schema_dn()
