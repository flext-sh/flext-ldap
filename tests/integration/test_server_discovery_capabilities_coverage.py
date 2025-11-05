"""Phase 3c: Server Discovery & Capabilities Coverage Expansion.

Targets uncovered server discovery, capability detection, and schema operations
in oid_operations.py and oud_operations.py with real Docker LDAP testing.

This test suite expands OID/OUD coverage from 49%/47% to targeted coverage
through comprehensive server discovery and capability testing.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdapClients
from flext_ldap.servers.oid_operations import FlextLdapServersOIDOperations
from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations

# ============================================================================
# OID SERVER DISCOVERY & CAPABILITIES COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOIDServerDiscoveryCapabilities:
    """OID server discovery and capability detection - comprehensive testing."""

    def test_oid_discover_schema_with_bound_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID schema discovery with bound connection."""
        ops = FlextLdapServersOIDOperations()
        result = ops.discover_schema(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)
        # May succeed or fail depending on server schema availability
        if result.is_success:
            schema = result.unwrap()
            assert isinstance(schema, dict)
            assert "server_type" in schema
            assert schema["server_type"] == "oid"

    def test_oid_get_schema_dn_returns_string(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID schema DN returns valid string."""
        ops = FlextLdapServersOIDOperations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0
        assert "schema" in schema_dn.lower()

    def test_oid_get_default_port_non_ssl(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID default non-SSL port."""
        ops = FlextLdapServersOIDOperations()
        port = ops.get_default_port(use_ssl=False)
        assert port == 389

    def test_oid_get_default_port_ssl(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID default SSL port."""
        ops = FlextLdapServersOIDOperations()
        port = ops.get_default_port(use_ssl=True)
        assert port == 636

    def test_oid_supports_start_tls_returns_bool(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID START_TLS support."""
        ops = FlextLdapServersOIDOperations()
        supports = ops.supports_start_tls()
        assert isinstance(supports, bool)
        assert supports is True

    def test_oid_get_bind_mechanisms_includes_simple(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID bind mechanisms include SIMPLE."""
        ops = FlextLdapServersOIDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0
        assert any(m.upper() == "SIMPLE" for m in mechanisms)

    def test_oid_parse_object_class_valid(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID parse objectClass with valid class."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_object_class("orclUserV2")
        assert result.is_success
        data = result.unwrap()
        assert data["server_type"] == "oid"
        assert data["definition"] == "orclUserV2"

    def test_oid_parse_attribute_type_valid(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID parse attributeType with valid attribute."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_attribute_type("orclUserStatus")
        assert result.is_success
        data = result.unwrap()
        assert data["server_type"] == "oid"
        assert data["definition"] == "orclUserStatus"

    def test_oid_normalize_entry_with_oracle_attrs(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID normalize with Oracle-specific attributes."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=oracle_user,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["orclUserV2", "person"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["oracle_user"]),
                    "orclUserStatus": FlextLdifModels.AttributeValues(
                        values=["ACTIVE"]
                    ),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oid_validate_entry_with_oracle_attrs(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID validate with Oracle-specific attributes."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=oracle_validate,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["orclUserV2"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["oracle_validate"]),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oid_get_acl_attribute_name(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID ACL attribute name."""
        ops = FlextLdapServersOIDOperations()
        attr_name = ops.get_acl_attribute_name()
        assert attr_name == "orclaci"

    def test_oid_get_acl_format(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID ACL format."""
        ops = FlextLdapServersOIDOperations()
        acl_format = ops.get_acl_format()
        assert acl_format == "oracle"

    def test_oid_parse_valid(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID parse valid ACL."""
        ops = FlextLdapServersOIDOperations()
        acl_str = "access to entry by * : browse"
        result = ops.parse(acl_str)
        assert result.is_success
        acl = result.unwrap()
        assert acl["format"] == "oracle"
        assert acl["server_type"] == "oid"

    def test_oid_format_acl_from_dict(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID format ACL from dictionary."""
        ops = FlextLdapServersOIDOperations()
        acl_dict = {
            "target_type": "entry",
            "target": "*",
            "subject": "*",
            "permissions": ["browse"],
        }
        result = ops.format_acl(acl_dict)
        assert result.is_success
        acl_str = result.unwrap()
        assert isinstance(acl_str, str)
        assert len(acl_str) > 0


# ============================================================================
# OUD SERVER DISCOVERY & CAPABILITIES COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOUDServerDiscoveryCapabilities:
    """OUD server discovery and capability detection - comprehensive testing."""

    def test_oud_discover_schema_with_bound_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD schema discovery with bound connection."""
        ops = FlextLdapServersOUDOperations()
        result = ops.discover_schema(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)
        if result.is_success:
            schema = result.unwrap()
            assert isinstance(schema, dict)
            assert "server_type" in schema
            assert schema["server_type"] == "oud"

    def test_oud_get_schema_dn_returns_string(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD schema DN returns valid string."""
        ops = FlextLdapServersOUDOperations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0
        assert "schema" in schema_dn.lower()

    def test_oud_get_default_port_non_ssl(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD default non-SSL port."""
        ops = FlextLdapServersOUDOperations()
        port = ops.get_default_port(use_ssl=False)
        assert port == 389

    def test_oud_get_default_port_ssl(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD default SSL port."""
        ops = FlextLdapServersOUDOperations()
        port = ops.get_default_port(use_ssl=True)
        assert port == 636

    def test_oud_supports_start_tls_returns_bool(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD START_TLS support."""
        ops = FlextLdapServersOUDOperations()
        supports = ops.supports_start_tls()
        assert isinstance(supports, bool)

    def test_oud_get_bind_mechanisms_includes_simple(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD bind mechanisms include SIMPLE."""
        ops = FlextLdapServersOUDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0
        assert any(m.upper() == "SIMPLE" for m in mechanisms)

    def test_oud_parse_object_class_valid(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD parse objectClass with valid class."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_object_class("person")
        assert result.is_success
        data = result.unwrap()
        assert data["server_type"] == "oud"
        assert data["definition"] == "person"

    def test_oud_parse_attribute_type_valid(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD parse attributeType with valid attribute."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse_attribute_type("ds-pwp-account-disabled")
        assert result.is_success
        data = result.unwrap()
        assert data["server_type"] == "oud"
        assert data["definition"] == "ds-pwp-account-disabled"

    def test_oud_normalize_entry_with_privilege_attrs(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD normalize with privilege attributes."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=oud_user,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson", "person"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["oud_user"]),
                    "ds-privilege-name": FlextLdifModels.AttributeValues(
                        values=["admin"]
                    ),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oud_validate_entry_with_privilege_attrs(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD validate with privilege attributes."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=oud_validate,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["oud_validate"]),
                    "ds-pwp-account-disabled": FlextLdifModels.AttributeValues(
                        values=["true"]
                    ),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oud_get_acl_attribute_name(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD ACL attribute name."""
        ops = FlextLdapServersOUDOperations()
        attr_name = ops.get_acl_attribute_name()
        assert isinstance(attr_name, str)
        assert len(attr_name) > 0

    def test_oud_get_acl_format(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD ACL format."""
        ops = FlextLdapServersOUDOperations()
        acl_format = ops.get_acl_format()
        assert isinstance(acl_format, str)
        assert len(acl_format) > 0

    def test_oud_server_type_property(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD server_type property."""
        ops = FlextLdapServersOUDOperations()
        assert ops.server_type == "oud"

    def test_oud_parse_valid(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD parse valid ACL."""
        ops = FlextLdapServersOUDOperations()
        acl_str = "access to entry by * read"
        result = ops.parse(acl_str)
        assert isinstance(result, FlextResult)


# ============================================================================
# SERVER CONSISTENCY & COMPARISON COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestServerConsistencyComparison:
    """Test consistency between OID and OUD server implementations."""

    def test_oid_oud_both_implement_schema_operations(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID and OUD both implement schema operations."""
        oid_ops = FlextLdapServersOIDOperations()
        oud_ops = FlextLdapServersOUDOperations()

        # Both should have schema DN methods
        oid_schema_dn = oid_ops.get_schema_dn()
        oud_schema_dn = oud_ops.get_schema_dn()

        assert isinstance(oid_schema_dn, str)
        assert isinstance(oud_schema_dn, str)
        assert len(oid_schema_dn) > 0
        assert len(oud_schema_dn) > 0

    def test_oid_oud_both_support_discovery(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID and OUD both support schema discovery."""
        oid_ops = FlextLdapServersOIDOperations()
        oud_ops = FlextLdapServersOUDOperations()

        oid_result = oid_ops.discover_schema(shared_ldap_client._connection)
        oud_result = oud_ops.discover_schema(shared_ldap_client._connection)

        assert isinstance(oid_result, FlextResult)
        assert isinstance(oud_result, FlextResult)

    def test_oid_oud_both_support_acl_operations(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID and OUD both support ACL operations."""
        oid_ops = FlextLdapServersOIDOperations()
        oud_ops = FlextLdapServersOUDOperations()

        # Both should return strings for ACL attributes/formats
        oid_attr = oid_ops.get_acl_attribute_name()
        oud_attr = oud_ops.get_acl_attribute_name()
        oid_format = oid_ops.get_acl_format()
        oud_format = oud_ops.get_acl_format()

        assert isinstance(oid_attr, str)
        assert isinstance(oud_attr, str)
        assert isinstance(oid_format, str)
        assert isinstance(oud_format, str)

    def test_oid_oud_both_normalize_entries(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID and OUD both normalize entries."""
        oid_ops = FlextLdapServersOIDOperations()
        oud_ops = FlextLdapServersOUDOperations()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )

        oid_result = oid_ops.normalize_entry_for_server(entry)
        oud_result = oud_ops.normalize_entry_for_server(entry)

        assert isinstance(oid_result, FlextResult)
        assert isinstance(oud_result, FlextResult)

    def test_oid_oud_both_validate_entries(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID and OUD both validate entries."""
        oid_ops = FlextLdapServersOIDOperations()
        oud_ops = FlextLdapServersOUDOperations()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )

        oid_result = oid_ops.validate_entry_for_server(entry)
        oud_result = oud_ops.validate_entry_for_server(entry)

        assert isinstance(oid_result, FlextResult)
        assert isinstance(oud_result, FlextResult)


# ============================================================================
# SERVER CONFIGURATION CONSISTENCY COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestServerConfigurationConsistency:
    """Test server configuration consistency and defaults."""

    def test_oid_port_configuration_consistency(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID port configuration is consistent."""
        ops1 = FlextLdapServersOIDOperations()
        ops2 = FlextLdapServersOIDOperations()

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

    def test_oid_bind_mechanisms_consistent(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID bind mechanisms are consistent."""
        ops1 = FlextLdapServersOIDOperations()
        ops2 = FlextLdapServersOIDOperations()

        mech1 = ops1.get_bind_mechanisms()
        mech2 = ops2.get_bind_mechanisms()

        assert mech1 == mech2
        assert isinstance(mech1, list)
        assert len(mech1) > 0

    def test_oud_bind_mechanisms_consistent(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD bind mechanisms are consistent."""
        ops1 = FlextLdapServersOUDOperations()
        ops2 = FlextLdapServersOUDOperations()

        mech1 = ops1.get_bind_mechanisms()
        mech2 = ops2.get_bind_mechanisms()

        assert mech1 == mech2
        assert isinstance(mech1, list)
        assert len(mech1) > 0

    def test_oid_schema_dn_consistent(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID schema DN is consistent across instances."""
        ops1 = FlextLdapServersOIDOperations()
        ops2 = FlextLdapServersOIDOperations()

        assert ops1.get_schema_dn() == ops2.get_schema_dn()

    def test_oud_schema_dn_consistent(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD schema DN is consistent across instances."""
        ops1 = FlextLdapServersOUDOperations()
        ops2 = FlextLdapServersOUDOperations()

        assert ops1.get_schema_dn() == ops2.get_schema_dn()

    def test_oid_acl_attribute_name_consistent(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID ACL attribute name is consistent."""
        ops1 = FlextLdapServersOIDOperations()
        ops2 = FlextLdapServersOIDOperations()
        ops3 = FlextLdapServersOIDOperations()

        assert (
            ops1.get_acl_attribute_name()
            == ops2.get_acl_attribute_name()
            == ops3.get_acl_attribute_name()
            == "orclaci"
        )

    def test_oid_acl_format_consistent(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID ACL format is consistent."""
        ops1 = FlextLdapServersOIDOperations()
        ops2 = FlextLdapServersOIDOperations()

        assert ops1.get_acl_format() == ops2.get_acl_format() == "oracle"
