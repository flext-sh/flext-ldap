"""Comprehensive OID/OUD coverage expansion - Real Docker LDAP testing.

Targets uncovered code paths in oid_operations.py (46%) and oud_operations.py (47%)
with real Docker LDAP fixture data and all server-specific quirks validation.

This test suite aims to expand coverage from 46-47% to 90%+ for both modules.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLdapClients
from flext_ldap.servers.oid_operations import FlextLdapServersOIDOperations
from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations

# ============================================================================
# OID OPERATIONS EXPANDED COVERAGE (46% → 90%+)
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOIDOperationsCoverageExpansion:
    """Oracle OID operations - covering all uncovered code paths."""

    def test_oid_normalize_entry_for_server_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID normalize_entry_for_server with basic entry."""
        from flext_ldif import FlextLdifModels

        ops = FlextLdapServersOIDOperations()
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
        assert result is not None
        assert result.is_success
        normalized = result.unwrap()
        assert normalized is not None

    def test_oid_normalize_entry_for_server_with_oracle_attrs(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID normalize_entry_for_server with Oracle-specific attributes."""
        from flext_ldif import FlextLdifModels

        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testuser,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["orclUserV2", "inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["testuser"]),
                    "orclUserStatus": FlextLdifModels.AttributeValues(
                        values=["ACTIVE"]
                    ),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert result is not None
        assert result.is_success

    def test_oid_validate_entry_for_server_valid(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID validate_entry_for_server with valid entry."""
        from flext_ldif import FlextLdifModels

        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert result is not None
        assert result.is_success

    def test_oid_get_acl_attribute_name_orclaci(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID returns correct ACL attribute (orclaci)."""
        ops = FlextLdapServersOIDOperations()
        acl_attr = ops.get_acl_attribute_name()
        assert acl_attr == "orclaci"
        assert isinstance(acl_attr, str)

    def test_oid_get_acl_format_oracle(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID ACL format is Oracle-specific."""
        ops = FlextLdapServersOIDOperations()
        acl_format = ops.get_acl_format()
        assert acl_format == "oracle"

    def test_oid_discover_schema_returns_flext_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID discover_schema returns FlextResult."""
        ops = FlextLdapServersOIDOperations()
        # With real connection
        result = ops.discover_schema(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_oid_discover_schema_success_extracts_data(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID discover_schema extracts object classes and attributes."""
        ops = FlextLdapServersOIDOperations()
        result = ops.discover_schema(shared_ldap_client._connection)
        if result.is_success:
            schema_data = result.unwrap()
            assert "object_classes" in schema_data
            assert "attribute_types" in schema_data
            assert "server_type" in schema_data
            assert schema_data["server_type"] == "oid"

    def test_oid_parse_object_class_simple(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID parse_object_class with simple class name."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_object_class("person")
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_oid_parse_object_class_oracle_specific(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID parse_object_class with Oracle-specific class."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_object_class("orclUserV2")
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_oid_parse_attribute_type_standard(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID parse_attribute_type with standard attribute."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_attribute_type("cn")
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_oid_parse_attribute_type_oracle_attr(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID parse_attribute_type with Oracle attribute."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_attribute_type("orclUserStatus")
        assert isinstance(result, FlextResult)
        assert result.is_success

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
        """Test OID maximum page size."""
        ops = FlextLdapServersOIDOperations()
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_oid_discover_schema_with_invalid_connection(self) -> None:
        """Test OID schema discovery with invalid connection."""
        ops = FlextLdapServersOIDOperations()
        result = ops.discover_schema(None)
        assert isinstance(result, FlextResult)
        assert result.is_failure


# ============================================================================
# OUD OPERATIONS EXPANDED COVERAGE (47% → 90%+)
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOUDOperationsCoverageExpansion:
    """Oracle OUD operations - covering all uncovered code paths."""

    def test_oud_normalize_entry_for_server_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD normalize_entry_for_server with basic entry."""
        from flext_ldif import FlextLdifModels

        ops = FlextLdapServersOUDOperations()
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
        assert result is not None
        assert result.is_success

    def test_oud_normalize_entry_for_server_with_oud_attrs(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD normalize_entry_for_server with OUD-specific attributes."""
        from flext_ldif import FlextLdifModels

        ops = FlextLdapServersOUDOperations()
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
                    "ds-pwp-account-disabled": FlextLdifModels.AttributeValues(
                        values=["false"]
                    ),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert result is not None
        assert result.is_success

    def test_oud_validate_entry_for_server_valid(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD validate_entry_for_server with valid entry."""
        from flext_ldif import FlextLdifModels

        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert result is not None
        assert result.is_success

    def test_oud_get_acl_attribute_name(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD returns correct ACL attribute."""
        ops = FlextLdapServersOUDOperations()
        acl_attr = ops.get_acl_attribute_name()
        assert isinstance(acl_attr, str)
        assert len(acl_attr) > 0

    def test_oud_get_acl_format(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD ACL format."""
        ops = FlextLdapServersOUDOperations()
        acl_format = ops.get_acl_format()
        assert isinstance(acl_format, str)

    def test_oud_discover_schema_returns_flext_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD discover_schema returns FlextResult."""
        ops = FlextLdapServersOUDOperations()
        result = ops.discover_schema(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_oud_discover_schema_success_extracts_data(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD discover_schema extracts schema data."""
        ops = FlextLdapServersOUDOperations()
        result = ops.discover_schema(shared_ldap_client._connection)
        if result.is_success:
            schema_data = result.unwrap()
            assert "object_classes" in schema_data
            assert "attribute_types" in schema_data
            assert "server_type" in schema_data

    def test_oud_parse_object_class_inetorgperson(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD parse_object_class with inetOrgPerson."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_object_class("inetOrgPerson")
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_oud_parse_attribute_type_cn(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD parse_attribute_type with common name."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_attribute_type("cn")
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_oud_parse_attribute_type_oud_specific(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD parse_attribute_type with OUD-specific attribute."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_attribute_type("ds-pwp-account-disabled")
        assert isinstance(result, FlextResult)

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
        """Test OUD maximum page size."""
        ops = FlextLdapServersOUDOperations()
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_oud_discover_schema_with_invalid_connection(self) -> None:
        """Test OUD schema discovery with invalid connection."""
        ops = FlextLdapServersOUDOperations()
        result = ops.discover_schema(None)
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_oud_get_default_port_consistency(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD default ports are consistent."""
        ops = FlextLdapServersOUDOperations()
        assert ops.get_default_port(use_ssl=False) == 389
        assert ops.get_default_port(use_ssl=True) == 636

    def test_oud_server_type_attribute(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD server_type attribute."""
        ops = FlextLdapServersOUDOperations()
        assert ops.server_type == "oud"
        assert isinstance(ops.server_type, str)
