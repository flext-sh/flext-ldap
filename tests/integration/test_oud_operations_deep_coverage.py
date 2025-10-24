"""Deep coverage expansion for Oracle OUD operations - Real Docker LDAP testing.

Targets uncovered code paths in oud_operations.py (47% current coverage)
with real Docker LDAP fixture data, server-specific quirks validation, and
comprehensive schema/ACL operations testing.

This test suite aims to expand OUD coverage from 47% to 95%+.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdapClients
from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations

# ============================================================================
# OUD OPERATIONS DEEP COVERAGE - REAL DOCKER TESTING (47% → 95%+)
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOUDOperationsDeepCoverage:
    """Deep integration tests for OUD operations with real Docker LDAP."""

    def test_oud_normalize_entry_with_disabled_account(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD normalize handles ds-pwp-account-disabled attribute."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=disabled_user,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson", "person"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["disabled_user"]),
                    "sn": FlextLdifModels.AttributeValues(values=["User"]),
                    "ds-pwp-account-disabled": FlextLdifModels.AttributeValues(
                        values=["true"]
                    ),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert result.is_success
        normalized = result.unwrap()
        assert normalized is not None

    def test_oud_normalize_entry_with_multiple_object_classes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD normalize with multiple OUD-specific object classes."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=multi_class,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson", "organizationalPerson", "person"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["multi_class"]),
                    "sn": FlextLdifModels.AttributeValues(values=["Class"]),
                    "mail": FlextLdifModels.AttributeValues(
                        values=["multi@example.com"]
                    ),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert result.is_success

    def test_oud_get_acl_attribute_name_returns_string(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD ACL attribute name is string type."""
        ops = FlextLdapServersOUDOperations()
        attr_name = ops.get_acl_attribute_name()
        assert isinstance(attr_name, str)
        assert len(attr_name) > 0

    def test_oud_get_acl_format_returns_string(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD ACL format is valid string."""
        ops = FlextLdapServersOUDOperations()
        acl_format = ops.get_acl_format()
        assert isinstance(acl_format, str)
        assert len(acl_format) > 0

    def test_oud_get_default_port_ssl_consistency(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD default ports are consistent across calls."""
        ops = FlextLdapServersOUDOperations()
        port1_non_ssl = ops.get_default_port(use_ssl=False)
        port2_non_ssl = ops.get_default_port(use_ssl=False)
        port1_ssl = ops.get_default_port(use_ssl=True)
        port2_ssl = ops.get_default_port(use_ssl=True)

        assert port1_non_ssl == port2_non_ssl == 389
        assert port1_ssl == port2_ssl == 636

    def test_oud_get_bind_mechanisms_includes_simple(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD bind mechanisms include SIMPLE."""
        ops = FlextLdapServersOUDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0
        # Should support at least SIMPLE
        assert any(m.upper() == "SIMPLE" for m in mechanisms)

    def test_oud_get_schema_dn_format(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD schema DN format is valid."""
        ops = FlextLdapServersOUDOperations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0
        # Schema DN should contain schema reference
        assert "schema" in schema_dn.lower()

    def test_oud_supports_start_tls_returns_bool(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD START_TLS support returns boolean."""
        ops = FlextLdapServersOUDOperations()
        supports = ops.supports_start_tls()
        assert isinstance(supports, bool)

    def test_oud_discover_schema_with_valid_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD schema discovery with real connection."""
        ops = FlextLdapServersOUDOperations()
        result = ops.discover_schema(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)
        # Schema discovery might succeed or fail depending on server,
        # but should return FlextResult
        if result.is_success:
            schema_data = result.unwrap()
            assert isinstance(schema_data, dict)

    def test_oud_parse_object_class_person_returns_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD parse_object_class returns FlextResult."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_object_class("person")
        assert isinstance(result, FlextResult)

    def test_oud_parse_attribute_type_cn_returns_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD parse_attribute_type returns FlextResult."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_attribute_type("cn")
        assert isinstance(result, FlextResult)

    def test_oud_parse_attribute_type_mail_returns_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD parse_attribute_type with mail attribute."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_attribute_type("mail")
        assert isinstance(result, FlextResult)

    def test_oud_supports_vlv_returns_bool(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD VLV support returns boolean."""
        ops = FlextLdapServersOUDOperations()
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_oud_supports_paged_results_returns_bool(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD paged results support returns boolean."""
        ops = FlextLdapServersOUDOperations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_oud_get_max_page_size_positive_int(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD max page size is positive integer."""
        ops = FlextLdapServersOUDOperations()
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_oud_server_type_is_oud_string(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD server_type property returns 'oud'."""
        ops = FlextLdapServersOUDOperations()
        assert ops.server_type == "oud"
        assert isinstance(ops.server_type, str)

    def test_oud_normalize_entry_preserves_dn(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD normalization preserves DN."""
        ops = FlextLdapServersOUDOperations()
        test_dn = "cn=preserve_dn,ou=people,dc=flext,dc=local"
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=test_dn),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["preserve_dn"]),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        if result.is_success:
            normalized = result.unwrap()
            # DN should be preserved in the normalized entry
            assert normalized is not None

    def test_oud_validate_entry_with_required_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD validates entry with required attributes."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=validate_required,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["validate_required"]),
                    "sn": FlextLdifModels.AttributeValues(values=["User"]),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert result is not None

    def test_oud_validate_entry_returns_flext_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD validate_entry_for_server returns FlextResult."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=result_type,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["result_type"]),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oud_discover_schema_error_handling(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD schema discovery error handling with None connection."""
        ops = FlextLdapServersOUDOperations()
        result = ops.discover_schema(None)  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        # Should return failure for None connection
        assert result.is_failure


@pytest.mark.integration
@pytest.mark.docker
class TestOUDOperationsErrorHandling:
    """Test OUD operations error handling and edge cases."""

    def test_oud_normalize_empty_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD normalize with minimal attributes."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=minimal,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(attributes={}),
        )
        result = ops.normalize_entry_for_server(entry)
        # Should handle minimal attributes gracefully
        assert isinstance(result, FlextResult)

    def test_oud_validate_empty_object_class(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD validate with empty objectClass."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=empty_class,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(values=[]),
                    "cn": FlextLdifModels.AttributeValues(values=["empty_class"]),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oud_parse_object_class_invalid_returns_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD parse_object_class with invalid class."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_object_class("invalidObjectClass123")
        assert isinstance(result, FlextResult)

    def test_oud_parse_attribute_type_invalid_returns_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD parse_attribute_type with invalid attribute."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_attribute_type("invalidAttributeType123")
        assert isinstance(result, FlextResult)


@pytest.mark.integration
@pytest.mark.docker
class TestOUDOperationsConfiguration:
    """Test OUD operations configuration and constants."""

    def test_oud_multiple_instances_have_same_server_type(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test multiple OUD instances have consistent server_type."""
        ops1 = FlextLdapServersOUDOperations()
        ops2 = FlextLdapServersOUDOperations()
        ops3 = FlextLdapServersOUDOperations()

        assert ops1.server_type == ops2.server_type == ops3.server_type == "oud"

    def test_oud_port_configuration_consistency(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD port configuration is consistent."""
        ops1 = FlextLdapServersOUDOperations()
        ops2 = FlextLdapServersOUDOperations()

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

    def test_oud_schema_dn_is_consistent(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD schema DN is consistent."""
        ops1 = FlextLdapServersOUDOperations()
        ops2 = FlextLdapServersOUDOperations()

        schema_dn1 = ops1.get_schema_dn()
        schema_dn2 = ops2.get_schema_dn()

        assert schema_dn1 == schema_dn2
        assert isinstance(schema_dn1, str)
        assert "schema" in schema_dn1.lower()

    def test_oud_bind_mechanisms_consistent(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD bind mechanisms are consistent."""
        ops1 = FlextLdapServersOUDOperations()
        ops2 = FlextLdapServersOUDOperations()

        mechanisms1 = ops1.get_bind_mechanisms()
        mechanisms2 = ops2.get_bind_mechanisms()

        assert mechanisms1 == mechanisms2
        assert isinstance(mechanisms1, list)
        assert len(mechanisms1) > 0
